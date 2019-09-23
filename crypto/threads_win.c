/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if defined(_WIN32)
# include <windows.h>
#endif

#include <openssl/crypto.h>

#if defined(OPENSSL_THREADS) && !defined(CRYPTO_TDEBUG) && defined(OPENSSL_SYS_WINDOWS)

volatile int CRYPTO_THREAD_EXTERN_enabled = 0;
volatile int CRYPTO_THREAD_INTERN_enabled = 0;

typedef struct {
    CRYPTO_THREAD_CALLBACK callback;
    HANDLE * handle;
} CRYPTO_THREAD_WIN;

/** CRYPTO THREAD: External -- currently not supported for Windows **/

int CRYPTO_THREAD_EXTERN_enable(CRYPTO_SIGNAL_PROPS *props)
{
    return 0;
}

int CRYPTO_THREAD_EXTERN_disable(void)
{
    return 1;
}

void * CRYPTO_THREAD_EXTERN_handle(void * data)
{
    (void) ret;
    return NULL;
}

void * CRYPTO_THREAD_EXTERN_provide(int * ret)
{
    (void) ret;
    return NULL;
}

void * CRYPTO_THREAD_EXTERN_add_job(CRYPTO_THREAD_ROUTINE task, void * data)
{
    (void) task;
    (void) data;
    return NULL;
}

int CRYPTO_THREAD_EXTERN_join(void * task_id, unsigned long * retval)
{
    (void) task_id;
    (void) retval;
    return 0;
}

# ifndef CRYPTO_THREAD_EXTERN_exit
#  define CRYPTO_THREAD_EXTERN_exit return
# endif

/** CRYPTO THREAD: Internal **/

# ifdef OPENSSL_NO_INTERN_THREAD

int CRYPTO_THREAD_INTERN_enable(CRYPTO_SIGNAL_PROPS *props)
{
    return 0;
}

int CRYPTO_THREAD_INTERN_disable(void)
{
    return 1;
}

# else /* ! OPENSSL_NO_EXTERN_THREAD */

extern CRYPTO_SIGNAL_CALLBACK cb_ctrl_c_event;
extern CRYPTO_SIGNAL_CALLBACK cb_break_event;

int CRYPTO_THREAD_INTERN_enable(CRYPTO_SIGNAL_PROPS *props)
{
    if (props == NULL)
        return 0;

    if (CRYPTO_SIGNAL_block(CTRL_C_EVENT, props->cb_ctrl_c_event) != 1)
        goto fail;

    if (CRYPTO_SIGNAL_block(CTRL_BREAK_EVENT, props->cb_ctrl_break_event) != 1)
        goto fail;

    if (CRYPTO_SIGNAL_block(CTRL_CLOSE_EVENT, props->cb_ctrl_close_event) != 1)
        goto fail;

    CRYPTO_THREAD_INTERN_enabled = 1;
    return 1;

fail:

    CRYPTO_THREAD_INTERN_disable();
    return 0;
}

int CRYPTO_THREAD_INTERN_disable()
{
    CRYPTO_SIGNAL_block(CTRL_C_EVENT, NULL);
    CRYPTO_SIGNAL_block(CTRL_BREAK_EVENT, NULL);
    CRYPTO_SIGNAL_block(CTRL_CLOSE_EVENT, NULL);

    CRYPTO_THREAD_INTERN_enabled = 0;
    return 1;
}

# endif

void * CRYPTO_THREAD_INTERN_new(CRYPTO_THREAD_ROUTINE start, void *data)
{
    CRYPTO_THREAD * thread;
    LPTHREAD_START_ROUTINE start_routine = (LPTHREAD_START_ROUTINE) start;

    if (CRYPTO_THREAD_INTERN_enabled == 0)
        return NULL;

    if ((thread = OPENSSL_zalloc(sizeof(*thread))) == NULL)
        return NULL;

    if ((thread->handle = OPENSSL_zalloc(sizeof(*thread->handle))) == NULL)
        return NULL;

    *thread->handle = CreateThread(NULL, 0, start_routine, data, 0, NULL);
    if (thread->handle == NULL) {
        OPENSSL_free(thread->handle);
        OPENSSL_free(thread);
        return NULL;
    }

    return (void *) thread;
}

int CRYPTO_THREAD_INTERN_join(void * thread, unsigned long * retval)
{
    CRYPTO_THREAD_WIN * thread_w = (CRYPTO_THREAD_WIN *) thread;

    if (WaitForSingleObject(*thread_w->handle, INFINITE) != WAIT_OBJECT_0)
        return 0;

    if (GetExitCodeThread(*thread_w->handle, (LPDWORD) &retval) == 0)
        return 0;

    if (CloseHandle(*thread->handle) == 0)
        return 0;

    return 1;
}

void CRYPTO_THREAD_INTERN_exit(unsigned long retval)
{
    ExitThread(retval);
}

CRYPTO_RWLOCK *CRYPTO_THREAD_lock_new(void)
{
    CRYPTO_RWLOCK *lock;

    if ((lock = OPENSSL_zalloc(sizeof(CRITICAL_SECTION))) == NULL) {
        /* Don't set error, to avoid recursion blowup. */
        return NULL;
    }

# if !defined(_WIN32_WCE)
    /* 0x400 is the spin count value suggested in the documentation */
    if (!InitializeCriticalSectionAndSpinCount(lock, 0x400)) {
        OPENSSL_free(lock);
        return NULL;
    }
# else
    InitializeCriticalSection(lock);
# endif

    return lock;
}

int CRYPTO_THREAD_read_lock(CRYPTO_RWLOCK *lock)
{
    EnterCriticalSection(lock);
    return 1;
}

int CRYPTO_THREAD_write_lock(CRYPTO_RWLOCK *lock)
{
    EnterCriticalSection(lock);
    return 1;
}

int CRYPTO_THREAD_unlock(CRYPTO_RWLOCK *lock)
{
    LeaveCriticalSection(lock);
    return 1;
}

void CRYPTO_THREAD_lock_free(CRYPTO_RWLOCK *lock)
{
    if (lock == NULL)
        return;

    DeleteCriticalSection(lock);
    OPENSSL_free(lock);

    return;
}

#  define ONCE_UNINITED     0
#  define ONCE_ININIT       1
#  define ONCE_DONE         2

/*
 * We don't use InitOnceExecuteOnce because that isn't available in WinXP which
 * we still have to support.
 */
int CRYPTO_THREAD_run_once(CRYPTO_ONCE *once, void (*init)(void))
{
    LONG volatile *lock = (LONG *)once;
    LONG result;

    if (*lock == ONCE_DONE)
        return 1;

    do {
        result = InterlockedCompareExchange(lock, ONCE_ININIT, ONCE_UNINITED);
        if (result == ONCE_UNINITED) {
            init();
            *lock = ONCE_DONE;
            return 1;
        }
    } while (result == ONCE_ININIT);

    return (*lock == ONCE_DONE);
}

int CRYPTO_THREAD_init_local(CRYPTO_THREAD_LOCAL *key, void (*cleanup)(void *))
{
    *key = TlsAlloc();
    if (*key == TLS_OUT_OF_INDEXES)
        return 0;

    return 1;
}

void *CRYPTO_THREAD_get_local(CRYPTO_THREAD_LOCAL *key)
{
    DWORD last_error;
    void *ret;

    /*
     * TlsGetValue clears the last error even on success, so that callers may
     * distinguish it successfully returning NULL or failing. It is documented
     * to never fail if the argument is a valid index from TlsAlloc, so we do
     * not need to handle this.
     *
     * However, this error-mangling behavior interferes with the caller's use of
     * GetLastError. In particular SSL_get_error queries the error queue to
     * determine whether the caller should look at the OS's errors. To avoid
     * destroying state, save and restore the Windows error.
     *
     * https://msdn.microsoft.com/en-us/library/windows/desktop/ms686812(v=vs.85).aspx
     */
    last_error = GetLastError();
    ret = TlsGetValue(*key);
    SetLastError(last_error);
    return ret;
}

int CRYPTO_THREAD_set_local(CRYPTO_THREAD_LOCAL *key, void *val)
{
    if (TlsSetValue(*key, val) == 0)
        return 0;

    return 1;
}

int CRYPTO_THREAD_cleanup_local(CRYPTO_THREAD_LOCAL *key)
{
    if (TlsFree(*key) == 0)
        return 0;

    return 1;
}

CRYPTO_THREAD_ID CRYPTO_THREAD_get_current_id(void)
{
    return GetCurrentThreadId();
}

int CRYPTO_THREAD_compare_id(CRYPTO_THREAD_ID a, CRYPTO_THREAD_ID b)
{
    return (a == b);
}

int CRYPTO_atomic_add(int *val, int amount, int *ret, CRYPTO_RWLOCK *lock)
{
    *ret = InterlockedExchangeAdd(val, amount) + amount;
    return 1;
}

int openssl_init_fork_handlers(void)
{
    return 0;
}

int openssl_get_fork_id(void)
{
    return 0;
}
#endif
