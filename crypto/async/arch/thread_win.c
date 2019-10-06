
#include "openssl/crypto.h"

#include "thread_win.h"

static DWORD WINAPI thread_call_routine(LPVOID param)
{
    CRYPTO_THREAD_WIN* thread = (CRYPTO_THREAD_WIN*) param;
    thread->retval = thread->routine(thread->data);
    return 0L;
}

static CRYPTO_THREAD thread_create(CRYPTO_THREAD_ROUTINE routine,
                                   CRYPTO_THREAD_DATA data)
{
    CRYPTO_THREAD_WIN * thread;

    if (CRYPTO_THREAD_EXTERN_enabled != 1)
        return NULL;

    if ((thread = OPENSSL_zalloc(sizeof(*thread))) == NULL)
        return NULL;

    if ((thread->handle = OPENSSL_zalloc(sizeof(*thread->handle))) == NULL)
        return NULL;

    thread->routine = routine;
    thread->data = arg;

    *thread->handle = CreateThread(NULL, 0, thread_call_routine,
                                   (LPVOID)thread, 0, NULL);

    if (thread->handle == NULL) {
        OPENSSL_free(thread->handle);
        OPENSSL_free(thread);
        return NULL;
    }

    return (CRYPTO_THREAD) thread;
}

static int thread_join(CRYPTO_THREAD thread, CRYPTO_THREAD_RETVAL* retval)
{
    DWORD retval_intern;

    if (thread == NULL)
        return 0;

    CRYPTO_THREAD_WIN* thread_w = (CRYPTO_THREAD_WIN*)thread;

    if (WaitForSingleObject(*thread_w->handle, INFINITE) != WAIT_OBJECT_0)
        return 0;

    if (GetExitCodeThread(*thread_w->handle, &retval_intern) == 0)
        return 0;

    if (CloseHandle(*thread_w->handle) == 0)
        return 0;

    *retval = thread_w->retval;

    return (retval_intern == 0);
}

static void thread_exit(CRYPTO_THREAD_RETVAL retval)
{
    /* @TODO */
    ExitThread((DWORD)retval);
}

static CRYPTO_MUTEX mutex_create(void)
{
    CRYPTO_MUTEX_POSIX* mutex;
    if ((mutex = OPENSSL_zalloc(sizeof(*mutex))) == NULL)
        return NULL;
    return (CRYPTO_MUTEX)mutex;
}

static int mutex_init(CRYPTO_MUTEX mutex)
{
    CRYPTO_MUTEX_WIN* mutex_p = (CRYPTO_MUTEX_POSIX*)mutex;
    InitializeCriticalSection(mutex_p);
    return 1;
}

static void mutex_lock(CRYPTO_MUTEX mutex)
{
    CRYPTO_MUTEX_WIN* mutex_p = (CRYPTO_MUTEX_POSIX*)mutex;
    EnterCriticalSection(mutex_p);
}

static void mutex_unlock(CRYPTO_MUTEX mutex)
{
    CRYPTO_MUTEX_WIN* mutex_p = (CRYPTO_MUTEX_POSIX*)mutex;
    LeaveCriticalSection(mutex_p);
}

static void mutex_destroy(CRYPTO_MUTEX* mutex)
{
    CRYPTO_MUTEX_WIN** mutex_p = (CRYPTO_MUTEX_POSIX**)mutex;
    DeleteCriticalSection(*mutex_p);
    OPENSSL_free(*mutex_p);
    *mutex = NULL;
}

static CRYPTO_CONDVAR condvar_create(void)
{
    CRYPTO_CONDVAR_WIN* cv_p;
    if ((mutex = OPENSSL_zalloc(sizeof(*cv_p))) == NULL)
        return NULL;
    return (CRYPTO_CONDVAR)cv_p;
}

static void condvar_wait(CRYPTO_CONDVAR cv, CRYPTO_MUTEX mutex)
{
    CRYPTO_CONDVAR_WIN* cv_p = (CRYPTO_CONDVAR_WIN*)cv;
    CRYPTO_MUTEX_WIN* mutex_p = (CRYPTO_MUTEX_WIN*)mutex;
    SleepConditionVariableCS(cv_p, mutex_p, INFINITE);
}

static int condvar_init(CRYPTO_CONDVAR cv)
{
    CRYPTO_CONDVAR_WIN* cv_p = (CRYPTO_CONDVAR_WIN*)cv;
    InitializeConditionVariable(cv_p);
    return 1;
}

static void condvar_broadcast(CRYPTO_CONDVAR cv)
{
    CRYPTO_CONDVAR_WIN* cv_p = (CRYPTO_CONDVAR_WIN*)cv;
    WakeAllConditionVariable(cv_p);
}

static void condvar_destroy(CRYPTO_CONDVAR cv)
{
    CRYPTO_CONDVAR_WIN* cv_p = (CRYPTO_CONDVAR_WIN*)cv;
    DeleteCriticalSection(cv_p);
    OPENSSL_free(*cv_p);
    *cv_p = NULL;
}

void mem_barrier()
{
    MemoryBarrier();
}