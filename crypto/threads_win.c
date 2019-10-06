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
#include "internal/threads.h"

#if defined(OPENSSL_THREADS) && !defined(CRYPTO_TDEBUG) && defined(OPENSSL_SYS_WINDOWS)

volatile int CRYPTO_THREAD_EXTERN_enabled = 0;
volatile int CRYPTO_THREAD_INTERN_enabled = 0;

typedef struct {
    HANDLE * handle;
} CRYPTO_THREAD_WIN;

/** CRYPTO THREAD: External **/

struct list        CRYPTO_THREAD_EXTERN_task_queue;
struct list        CRYPTO_THREAD_EXTERN_task_done;
CRITICAL_SECTION   CRYPTO_THREAD_EXTERN_task_lock;
CONDITION_VARIABLE CRYPTO_THREAD_EXTERN_task_cond_create;
CONDITION_VARIABLE CRYPTO_THREAD_EXTERN_task_cond_finish;

# ifdef OPENSSL_NO_EXTERN_THREAD

int CRYPTO_THREAD_EXTERN_enable(CRYPTO_SIGNAL_PROPS* props)
{
    return 0;
}

int CRYPTO_THREAD_EXTERN_disable()
{
    return 1;
}

# else /* ! OPENSSL_NO_EXTERN_THREAD */


int CRYPTO_THREAD_EXTERN_enable(CRYPTO_SIGNAL_PROPS *props)
{
    int ret = 0;

    if (CRYPTO_THREAD_EXTERN_enabled == 1)
        return 1;

    if (props == NULL)
        return 0;

    if (CRYPTO_SIGNAL_block(CTRL_C_EVENT, props->cb_ctrl_c) != 1)
        goto fail;

    if (CRYPTO_SIGNAL_block(CTRL_BREAK_EVENT, props->cb_ctrl_break) != 1)
        goto fail;

    if (CRYPTO_SIGNAL_block(CTRL_CLOSE_EVENT, props->cb_ctrl_close) != 1)
        goto fail;

    list_init(&CRYPTO_THREAD_EXTERN_task_queue);
    list_init(&CRYPTO_THREAD_EXTERN_task_done);

    CRYPTO_THREAD_INTERN_enabled = 1;
    return 1;

fail:

    CRYPTO_THREAD_INTERN_disable();
    return 0;
}

int CRYPTO_THREAD_EXTERN_disable(void)
{
    CRYPTO_SIGNAL_block(CTRL_C_EVENT, NULL);
    CRYPTO_SIGNAL_block(CTRL_BREAK_EVENT, NULL);
    CRYPTO_SIGNAL_block(CTRL_CLOSE_EVENT, NULL);

    CRYPTO_THREAD_EXTERN_enabled = 0;
    return 1;
}

static DWORD CALLBACK CRYPTO_THREAD_EXTERN_handle(LPVOID data)
{
    size_t task_cnt;
    CRYPTO_THREAD_CALLBACK cb = (CRYPTO_THREAD_CALLBACK)data;

    while (1) {
        EnterCriticalSection(&CRYPTO_THREAD_EXTERN_task_lock);

        /* To avoid spurious wakeups and to allow for immediate job
         * processing: */
        while (list_empty(&CRYPTO_THREAD_EXTERN_task_queue) == 1)
            SleepConditionVariableCS(&CRYPTO_THREAD_EXTERN_task_cond_create,
                                     &CRYPTO_THREAD_EXTERN_task_lock,
                                     INFINITE);

            struct list* job_l = CRYPTO_THREAD_EXTERN_task_queue.next;
            CRYPTO_THREAD_TASK* task = container_of(job_l, CRYPTO_THREAD_TASK,
                                                    list);
            list_del(job_l);
            LeaveCriticalSection(&CRYPTO_THREAD_EXTERN_task_lock);

            task->retval = task->task(task->data);
            list_add_tail(&task->list, &CRYPTO_THREAD_EXTERN_task_done);

            if (cb != NULL) {
                EnterCriticalSection(&CRYPTO_THREAD_EXTERN_task_lock);
                task_cnt = list_size(&CRYPTO_THREAD_EXTERN_task_queue);
                LeaveCriticalSection(&CRYPTO_THREAD_EXTERN_task_lock);

                if (cb(task_cnt) == 0)
                    break;
            }
    }

    return 0UL;
}

void * CRYPTO_THREAD_EXTERN_provide(int* ret, CRYPTO_THREAD_CALLBACK cb)
{
    CRYPTO_THREAD_WIN* thread;

    if (CRYPTO_THREAD_EXTERN_enabled != 1)
        return NULL;

    if ((thread = OPENSSL_zalloc(sizeof(*thread))) == NULL)
        return NULL;

    if ((thread->handle = OPENSSL_zalloc(sizeof(*thread->handle))) == NULL)
        return NULL;

    *thread->handle = CreateThread(NULL, 0, CRYPTO_THREAD_EXTERN_handle,
                                   (LPVOID) cb, 0, NULL);

    *ret = 0;
    if (thread->handle == NULL) {
        *ret = GetLastError();
        OPENSSL_free(thread->handle);
        OPENSSL_free(thread);
        return NULL;
    }

    return (void*)thread;
}

void * CRYPTO_THREAD_EXTERN_add_job(CRYPTO_THREAD_ROUTINE task, void * data)
{
    CRYPTO_THREAD_TASK* t;

    t = OPENSSL_zalloc(sizeof(*t));
    if (t == NULL)
        return NULL;

    t->task = task;
    t->data = data;

    EnterCriticalSection(&CRYPTO_THREAD_EXTERN_task_lock);
    list_add_tail(&t->list, &CRYPTO_THREAD_EXTERN_task_queue);
    WakeAllConditionVariable(&CRYPTO_THREAD_EXTERN_task_cond_create);
    LeaveCriticalSection(&CRYPTO_THREAD_EXTERN_task_lock);

    return (void*)t;
}

int CRYPTO_THREAD_EXTERN_join(void * task_id, unsigned long * retval)
{
    struct list* i;
    CRYPTO_THREAD_TASK* task = NULL;

loop:
    EnterCriticalSection(&CRYPTO_THREAD_EXTERN_task_lock);
    list_for_each(i, &CRYPTO_THREAD_EXTERN_task_done) {
        task = container_of(i, CRYPTO_THREAD_TASK, list);
        if (task == task_id)
            break;
    }

    if (task != task_id) {
        LeaveCriticalSection(&CRYPTO_THREAD_EXTERN_task_lock);
        Sleep(1000);
        goto loop;
    } else {
        list_del(&task->list);
        LeaveCriticalSection(&CRYPTO_THREAD_EXTERN_task_lock);
    }

    if (retval != NULL)
        *retval = task->retval;

    OPENSSL_free(task);
    task = NULL;

    return 1;
}

#  ifndef CRYPTO_THREAD_EXTERN_exit
#   define CRYPTO_THREAD_EXTERN_exit return
#  endif

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

extern CRYPTO_SIGNAL_CALLBACK cb_ctrl_c;
extern CRYPTO_SIGNAL_CALLBACK cb_break;

int CRYPTO_THREAD_INTERN_enable(CRYPTO_SIGNAL_PROPS *props)
{
    if (props == NULL)
        return 0;

    if (CRYPTO_SIGNAL_block(CTRL_C_EVENT, props->cb_ctrl_c) != 1)
        goto fail;

    if (CRYPTO_SIGNAL_block(CTRL_BREAK_EVENT, props->cb_ctrl_break) != 1)
        goto fail;

    if (CRYPTO_SIGNAL_block(CTRL_CLOSE_EVENT, props->cb_ctrl_close) != 1)
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

void * CRYPTO_THREAD_INTERN_new(CRYPTO_THREAD_ROUTINE start, void *data,
                                unsigned long *ret)
{
    CRYPTO_THREAD_WIN * thread;
    LPTHREAD_START_ROUTINE start_routine = (LPTHREAD_START_ROUTINE) start;

    if (CRYPTO_THREAD_INTERN_enabled == 0)
        return NULL;

    if ((thread = OPENSSL_zalloc(sizeof(*thread))) == NULL)
        return NULL;

    if ((thread->handle = OPENSSL_zalloc(sizeof(*thread->handle))) == NULL)
        return NULL;

    *thread->handle = CreateThread(NULL, 0, start_routine, data, 0, NULL);
    if (thread->handle == NULL) {
        *ret = GetLastError();
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

    if (CloseHandle(*thread_w->handle) == 0)
        return 0;

    return 1;
}

void CRYPTO_THREAD_INTERN_exit(unsigned long retval)
{
    ExitThread((DWORD) retval);
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
