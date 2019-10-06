
#ifndef OPENSSL_THREADS_H
# define OPENSSL_THREADS_H
# pragma once

# include <openssl/crypto.h>

enum {
    THREAD_ASYNC_RDY      = 1 << 0,
    THREAD_ASYNC_ERR      = 1 << 1,
    THREAD_ASYNC_CAPABLE  = 1 << 2,
};

void* CRYPTO_THREAD_INTERN_new(CRYPTO_THREAD_ROUTINE start, void* data,
                                      unsigned long* ret);
int   CRYPTO_THREAD_INTERN_join(void* thread, unsigned long* retval);
void  CRYPTO_THREAD_INTERN_exit(unsigned long retval);

void* CRYPTO_THREAD_EXTERN_add_job(CRYPTO_THREAD_ROUTINE task, void* data);
int   CRYPTO_THREAD_EXTERN_join(void* task_id, unsigned long* retval);

#endif /* OPENSSL_THREADS_H */