
#include "openssl/crypto.h"

#include "thread_posix.h"

static void* thread_call_routine(void* param)
{
    CRYPTO_THREAD_POSIX* thread = (CRYPTO_THREAD_WIN*)param;
    thread->retval = thread->routine(thread->data);
    return NULL;
}

static CRYPTO_THREAD thread_create(CRYPTO_THREAD_ROUTINE routine,
                                   CRYPTO_THREAD_DATA data)
{
    CRYPTO_THREAD_POSIX* thread;

    if (CRYPTO_THREAD_EXTERN_enabled != 1)
        return NULL;

    if ((thread = OPENSSL_zalloc(sizeof(*thread))) == NULL)
        return NULL;

    if ((thread->handle = OPENSSL_zalloc(sizeof(*thread->handle))) == NULL)
        return NULL;

    thread->routine = routine;
    thread->data = arg;

    retval = pthread_create(thread->handle, NULL, thread_call_routine,
                            (void*) data);

    if (retval != 0 || thread->handle == NULL) {
        OPENSSL_free(thread->handle);
        OPENSSL_free(thread);
        return NULL;
    }

    return (CRYPTO_THREAD) thread;
}

static int thread_join(CRYPTO_THREAD thread, CRYPTO_THREAD_RETVAL* retval)
{
    void* retval_intern;

    if (thread == NULL)
        return 0;

    CRYPTO_THREAD_POSIX* thread_p = (CRYPTO_THREAD_POSIX*)thread;

    if (pthread_join(*thread_p->handle, &retval_intern) != 0)
        return 0;

    *retval = thread_p->retval;

    return (retval_intern == NULL);
}

static void thread_exit(CRYPTO_THREAD_RETVAL retval)
{
    /* @TODO */
    pthread_exit((void*)retval);
}

static CRYPTO_MUTEX mutex_create(void)
{
    CRYPTO_MUTEX_POSIX* mutex;
    if ((mutex = OPENSSL_zalloc(sizeof(*mutex))) == NULL)
        return NULL;
    return (CRYPTO_MUTEX) mutex;
}

static int mutex_init(CRYPTO_MUTEX mutex)
{
    CRYPTO_MUTEX_POSIX* mutex_p = (CRYPTO_MUTEX_POSIX*)mutex;
    if (pthread_mutex_init(mutex_p, NULL) != 0)
        return 0;
    return 1;
}

static void mutex_lock(CRYPTO_MUTEX mutex)
{
    CRYPTO_MUTEX_POSIX* mutex_p = (CRYPTO_MUTEX_POSIX*)mutex;
    pthread_mutex_lock(mutex_p);
}

static void mutex_unlock(CRYPTO_MUTEX mutex)
{
    CRYPTO_MUTEX_POSIX* mutex_p = (CRYPTO_MUTEX_POSIX*)mutex;
    pthread_mutex_unlock(mutex_p);
}

static void mutex_destroy(CRYPTO_MUTEX* mutex)
{
    CRYPTO_MUTEX_POSIX** mutex_p = (CRYPTO_MUTEX_POSIX**)mutex;
    pthread_mutex_destroy(*mutex_p);
    OPENSSL_free(*mutex_p);
    *mutex = NULL;
}

static CRYPTO_CONDVAR condvar_create(void)
{
    CRYPTO_CONDVAR_POSIX* cv;
    if ((mutex = OPENSSL_zalloc(sizeof(*cv))) == NULL)
        return NULL;
    return (CRYPTO_CONDVAR) cv;
}

static void condvar_wait(CRYPTO_CONDVAR cv, CRYPTO_MUTEX mutex)
{
    CRYPTO_CONDVAR_POSIX* cv_p = (CRYPTO_CONDVAR_POSIX*)cv;
    CRYPTO_MUTEX_POSIX* mutex_p = (CRYPTO_MUTEX_POSIX*)mutex;
    pthread_cond_wait(cv_p, mutex_p);
}

static int condvar_init(CRYPTO_CONDVAR cv)
{
    CRYPTO_CONDVAR_POSIX* cv_p = (CRYPTO_CONDVAR_POSIX*)cv;
    if (pthread_cond_init(cv_p, NULL) != 0)
        return 0;
    return 1;
}

static void condvar_broadcast(CRYPTO_CONDVAR cv)
{
    CRYPTO_CONDVAR_POSIX* cv_p = (CRYPTO_CONDVAR_POSIX*)cv;
    pthread_cond_broadcast(cv_p);
}

static void condvar_destroy(CRYPTO_CONDVAR* cv)
{
    CRYPTO_CONDVAR_POSIX** cv_p = (CRYPTO_CONDVAR_POSIX**)cv;
    pthread_cond_destroy(*cv_p);
    OPENSSL_free(*cv_p);
    *cv_p = NULL;
}

void mem_barrier()
{
    asm volatile ("" : : : "memory");
}