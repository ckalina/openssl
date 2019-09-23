/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <signal.h>
#include "e_os.h"
#include <openssl/crypto.h>
#include <openssl/list.h>
#include "internal/cryptlib.h"

#if defined(__sun)
# include <atomic.h>
#endif

#if defined(OPENSSL_THREADS) && !defined(CRYPTO_TDEBUG) && !defined(OPENSSL_SYS_WINDOWS)

# if defined(OPENSSL_SYS_UNIX)
#  include <sys/types.h>
#  include <unistd.h>
#endif

# ifdef PTHREAD_RWLOCK_INITIALIZER
#  define USE_RWLOCK
# endif

volatile int CRYPTO_THREAD_EXTERN_enabled = 0;
volatile int CRYPTO_THREAD_INTERN_enabled = 0;

typedef struct {
    CRYPTO_THREAD_CALLBACK callback;
    pthread_t * handle;
} CRYPTO_THREAD_PTHREAD;

/** CRYPTO THREAD: External **/

struct list     CRYPTO_THREAD_EXTERN_task_queue;
struct list     CRYPTO_THREAD_EXTERN_task_done;
pthread_mutex_t CRYPTO_THREAD_EXTERN_task_lock;
pthread_cond_t  CRYPTO_THREAD_EXTERN_task_cond_create;
pthread_cond_t  CRYPTO_THREAD_EXTERN_task_cond_finish;

# ifdef OPENSSL_NO_EXTERN_THREAD

int CRYPTO_THREAD_EXTERN_enable(CRYPTO_SIGNAL_PROPS *props)
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

    if (CRYPTO_THREAD_EXTERN_enabled == 1) {
        return 1;
    }

    if (props == NULL)
        return 0;

    if (props->cb_sigint == NULL)
        props->cb_sigint = SIG_IGN;

    if (props->cb_sigterm == NULL)
        props->cb_sigterm = SIG_IGN;

    if (CRYPTO_SIGNAL_block(SIGINT, props->cb_sigint) != 1)
        return 0;

    if (CRYPTO_SIGNAL_block(SIGTERM, props->cb_sigterm) != 1)
        return 0;

    list_init(&CRYPTO_THREAD_EXTERN_task_queue);
    list_init(&CRYPTO_THREAD_EXTERN_task_done);

    if (pthread_mutex_init(&CRYPTO_THREAD_EXTERN_task_lock, NULL) != 0) {
        goto fail;
    }

    if (pthread_cond_init(&CRYPTO_THREAD_EXTERN_task_cond_create, NULL) != 0) {
        goto fail;
    }

    if (pthread_cond_init(&CRYPTO_THREAD_EXTERN_task_cond_finish, NULL) != 0) {
        goto fail;
    }

    asm volatile ("" : : : "memory");

    CRYPTO_THREAD_EXTERN_enabled = 1;
    ret = 1;

fail:
    return ret;
}

int CRYPTO_THREAD_EXTERN_disable()
{
    CRYPTO_THREAD_EXTERN_enabled = 0;

    if (CRYPTO_SIGNAL_block(SIGINT, SIG_DFL) != 1)
        return 0;

    if (CRYPTO_SIGNAL_block(SIGTERM, SIG_DFL) != 1)
        return 0;

    pthread_mutex_destroy(&CRYPTO_THREAD_EXTERN_task_lock);
    pthread_cond_destroy(&CRYPTO_THREAD_EXTERN_task_cond_create);
    pthread_cond_destroy(&CRYPTO_THREAD_EXTERN_task_cond_finish);
    return 1;
}

# endif /* ! OPENSSL_NO_EXTERN_THREAD */

void * CRYPTO_THREAD_EXTERN_handle(void * data)
{
    size_t task_cnt;
    int (*cb)(size_t) = (int (*)(size_t))data;

    while(1) {
        pthread_mutex_lock(&CRYPTO_THREAD_EXTERN_task_lock);

        /* To avoid spurious wakeups and to allow for immediate job
         * processing: */
        while (list_empty(&CRYPTO_THREAD_EXTERN_task_queue) == 1)
            pthread_cond_wait(&CRYPTO_THREAD_EXTERN_task_cond_create,
                              &CRYPTO_THREAD_EXTERN_task_lock);

        struct list *job_l = CRYPTO_THREAD_EXTERN_task_queue.next;
        CRYPTO_THREAD_TASK * task = container_of(job_l, CRYPTO_THREAD_TASK,
                                                 list);
        list_del(job_l);
        pthread_mutex_unlock(&CRYPTO_THREAD_EXTERN_task_lock);

        task->retval = task->task(task->data);
        list_add_tail(&task->list, &CRYPTO_THREAD_EXTERN_task_done);

        if (cb != NULL) {
            pthread_mutex_lock(&CRYPTO_THREAD_EXTERN_task_lock);
            task_cnt = list_size(&CRYPTO_THREAD_EXTERN_task_queue);
            pthread_mutex_unlock(&CRYPTO_THREAD_EXTERN_task_lock);

            if (cb(task_cnt) == 0)
                break;
        }
    }

    return NULL;
}

void * CRYPTO_THREAD_EXTERN_provide(int * ret, int (*cb)(size_t))
{
    CRYPTO_THREAD_PTHREAD * thread;

    if (CRYPTO_THREAD_EXTERN_enabled != 1)
        return NULL;

    if ((thread = OPENSSL_zalloc(sizeof(*thread))) == NULL)
        return NULL;

    if ((thread->handle = OPENSSL_zalloc(sizeof(*thread->handle))) == NULL)
        return NULL;

    *ret = pthread_create(thread->handle, NULL, CRYPTO_THREAD_EXTERN_handle,
                          (void *) cb);

    if (*ret != 0) {
        OPENSSL_free(thread->handle);
        OPENSSL_free(thread);
        return NULL;
    }

    return (void *) thread;
}

void * CRYPTO_THREAD_EXTERN_add_job(CRYPTO_THREAD_ROUTINE task, void * data)
{
    CRYPTO_THREAD_TASK * t;

    t = OPENSSL_zalloc(sizeof(*t));
    if (t == NULL)
        return NULL;

    t->task = task;
    t->data = data;

    pthread_mutex_lock(&CRYPTO_THREAD_EXTERN_task_lock);
    list_add_tail(&t->list, &CRYPTO_THREAD_EXTERN_task_queue);
    pthread_cond_broadcast(&CRYPTO_THREAD_EXTERN_task_cond_create);
    pthread_mutex_unlock(&CRYPTO_THREAD_EXTERN_task_lock);

    return (void *) t;
}

int CRYPTO_THREAD_EXTERN_join(void * task_id, unsigned long * retval)
{
    struct list *i;
    CRYPTO_THREAD_TASK *task = NULL;

loop:
    pthread_mutex_lock(&CRYPTO_THREAD_EXTERN_task_lock);
    list_for_each(i, &CRYPTO_THREAD_EXTERN_task_done) {
        task = container_of(i, CRYPTO_THREAD_TASK, list);
        if (task == task_id)
            break;
    }

    if (task != task_id) {
        pthread_mutex_unlock(&CRYPTO_THREAD_EXTERN_task_lock);
        sleep(1);
        goto loop;
    } else {
        list_del(&task->list);
        pthread_mutex_unlock(&CRYPTO_THREAD_EXTERN_task_lock);
    }

    if (retval != NULL)
        *retval = task->retval;

    OPENSSL_free(task);
    task = NULL;

    return 1;
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


int CRYPTO_THREAD_INTERN_enable(CRYPTO_SIGNAL_PROPS *props)
{
    if (props == NULL)
        return 0;

    if (props->cb_sigint == NULL)
        props->cb_sigint = SIG_IGN;

    if (props->cb_sigterm == NULL)
        props->cb_sigterm = SIG_IGN;

    if (CRYPTO_SIGNAL_block(SIGINT, props->cb_sigint) != 1)
        return 0;

    if (CRYPTO_SIGNAL_block(SIGTERM, props->cb_sigterm) != 1)
        return 0;

    asm volatile ("" : : : "memory");
    CRYPTO_THREAD_INTERN_enabled = 1;
    return 1;
}

int CRYPTO_THREAD_INTERN_disable(void)
{
    if (CRYPTO_SIGNAL_block(SIGINT, SIG_DFL) != 1)
        return 0;

    if (CRYPTO_SIGNAL_block(SIGTERM, SIG_DFL) != 1)
        return 0;

    asm volatile ("" : : : "memory");
    CRYPTO_THREAD_INTERN_enabled = 0;
    return 1;
}

# endif /* ! OPENSSL_NO_EXTERN_THREAD */

void * CRYPTO_THREAD_INTERN_new(CRYPTO_THREAD_ROUTINE start, void * data,
                                int * ret)
{
    int retval;

    CRYPTO_THREAD_PTHREAD * thread;
    void *(*start_routine)(void*) = (void *(*)(void*)) start;

    if (CRYPTO_THREAD_INTERN_enabled == 0)
        return NULL;

    if ((thread = OPENSSL_zalloc(sizeof(*thread))) == NULL)
        return NULL;

    if ((thread->handle = OPENSSL_zalloc(sizeof(*thread->handle))) == NULL)
        return NULL;

    retval = pthread_create(thread->handle, NULL, start_routine, data);

    if (ret != NULL)
        *ret = retval;

    if (retval != 0) {
        OPENSSL_free(thread->handle);
        OPENSSL_free(thread);
        return NULL;
    }

    return (void *) thread;
}

int CRYPTO_THREAD_INTERN_join(void * thread, unsigned long * retval)
{
    CRYPTO_THREAD_PTHREAD * thread_p = (CRYPTO_THREAD_PTHREAD *) thread;

    if (thread == NULL)
        return 0;

    if (pthread_join(*thread_p->handle, (void **)retval) != 0)
        return 0;

    return 1;
}

void CRYPTO_THREAD_INTERN_exit(unsigned long retval)
{
    pthread_exit((void*)retval);
}

CRYPTO_RWLOCK *CRYPTO_THREAD_lock_new(void)
{
# ifdef USE_RWLOCK
    CRYPTO_RWLOCK *lock;

    if ((lock = OPENSSL_zalloc(sizeof(pthread_rwlock_t))) == NULL) {
        /* Don't set error, to avoid recursion blowup. */
        return NULL;
    }

    if (pthread_rwlock_init(lock, NULL) != 0) {
        OPENSSL_free(lock);
        return NULL;
    }
# else
    pthread_mutexattr_t attr;
    CRYPTO_RWLOCK *lock;

    if ((lock = OPENSSL_zalloc(sizeof(pthread_mutex_t))) == NULL) {
        /* Don't set error, to avoid recursion blowup. */
        return NULL;
    }

    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

    if (pthread_mutex_init(lock, &attr) != 0) {
        pthread_mutexattr_destroy(&attr);
        OPENSSL_free(lock);
        return NULL;
    }

    pthread_mutexattr_destroy(&attr);
# endif

    return lock;
}

int CRYPTO_THREAD_read_lock(CRYPTO_RWLOCK *lock)
{
# ifdef USE_RWLOCK
    if (pthread_rwlock_rdlock(lock) != 0)
        return 0;
# else
    if (pthread_mutex_lock(lock) != 0)
        return 0;
# endif

    return 1;
}

int CRYPTO_THREAD_write_lock(CRYPTO_RWLOCK *lock)
{
# ifdef USE_RWLOCK
    if (pthread_rwlock_wrlock(lock) != 0)
        return 0;
# else
    if (pthread_mutex_lock(lock) != 0)
        return 0;
# endif

    return 1;
}

int CRYPTO_THREAD_unlock(CRYPTO_RWLOCK *lock)
{
# ifdef USE_RWLOCK
    if (pthread_rwlock_unlock(lock) != 0)
        return 0;
# else
    if (pthread_mutex_unlock(lock) != 0)
        return 0;
# endif

    return 1;
}

void CRYPTO_THREAD_lock_free(CRYPTO_RWLOCK *lock)
{
    if (lock == NULL)
        return;

# ifdef USE_RWLOCK
    pthread_rwlock_destroy(lock);
# else
    pthread_mutex_destroy(lock);
# endif
    OPENSSL_free(lock);

    return;
}

int CRYPTO_THREAD_run_once(CRYPTO_ONCE *once, void (*init)(void))
{
    if (pthread_once(once, init) != 0)
        return 0;

    return 1;
}

int CRYPTO_THREAD_init_local(CRYPTO_THREAD_LOCAL *key, void (*cleanup)(void *))
{
    if (pthread_key_create(key, cleanup) != 0)
        return 0;

    return 1;
}

void *CRYPTO_THREAD_get_local(CRYPTO_THREAD_LOCAL *key)
{
    return pthread_getspecific(*key);
}

int CRYPTO_THREAD_set_local(CRYPTO_THREAD_LOCAL *key, void *val)
{
    if (pthread_setspecific(*key, val) != 0)
        return 0;

    return 1;
}

int CRYPTO_THREAD_cleanup_local(CRYPTO_THREAD_LOCAL *key)
{
    if (pthread_key_delete(*key) != 0)
        return 0;

    return 1;
}

CRYPTO_THREAD_ID CRYPTO_THREAD_get_current_id(void)
{
    return pthread_self();
}

int CRYPTO_THREAD_compare_id(CRYPTO_THREAD_ID a, CRYPTO_THREAD_ID b)
{
    return pthread_equal(a, b);
}

int CRYPTO_atomic_add(int *val, int amount, int *ret, CRYPTO_RWLOCK *lock)
{
# if defined(__GNUC__) && defined(__ATOMIC_ACQ_REL)
    if (__atomic_is_lock_free(sizeof(*val), val)) {
        *ret = __atomic_add_fetch(val, amount, __ATOMIC_ACQ_REL);
        return 1;
    }
# elif defined(__sun) && (defined(__SunOS_5_10) || defined(__SunOS_5_11))
    /* This will work for all future Solaris versions. */
    if (ret != NULL) {
        *ret = atomic_add_int_nv((volatile unsigned int *)val, amount);
        return 1;
    }
# endif
    if (!CRYPTO_THREAD_write_lock(lock))
        return 0;

    *val += amount;
    *ret  = *val;

    if (!CRYPTO_THREAD_unlock(lock))
        return 0;

    return 1;
}

# ifndef FIPS_MODE
/* TODO(3.0): No fork protection in FIPS module yet! */

#  ifdef OPENSSL_SYS_UNIX
static pthread_once_t fork_once_control = PTHREAD_ONCE_INIT;

static void fork_once_func(void)
{
    pthread_atfork(OPENSSL_fork_prepare,
                   OPENSSL_fork_parent, OPENSSL_fork_child);
}
#  endif

int openssl_init_fork_handlers(void)
{
#  ifdef OPENSSL_SYS_UNIX
    if (pthread_once(&fork_once_control, fork_once_func) == 0)
        return 1;
#  endif
    return 0;
}
# endif /* FIPS_MODE */

int openssl_get_fork_id(void)
{
    return getpid();
}
#endif
