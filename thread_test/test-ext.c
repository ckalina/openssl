#include <stdio.h>
#include <unistd.h>
#include <openssl/crypto.h>

unsigned long rt(void *data) {
    printf("Thread created with data: %d.\n", *(int*)data);
    sleep(5);
    printf("Thread exitting.\n");
    return 1;
}

int worker_cb(size_t queue_size)
{
    printf("Some job finished, queue size: %ld.\n", queue_size);
    /* allow running until there is something in the queue */
    return ( queue_size > 0 );
}

int worker_kill_after_single_job(size_t queue_size)
{
    printf("Some job finished, queue size: %ld\n", queue_size);
    /* force worker termination */
    return 0;
}

int main(void)
{
    /* Attempting to create thread without explicit agreement. Should fail. */
    CRYPTO_THREAD t0;
    if ((t0 = CRYPTO_THREAD_provide(NULL)) != NULL) {
        /* ERROR: Created thread without explicit agreement. Cannot happen. */
        return 1;
    }

    /* Allow external threads. */
    CRYPTO_SIGNAL* s[] = {NULL};
    if (CRYPTO_THREAD_EXTERN_enable((CRYPTO_SIGNAL**)&s) == 0) {
        /* ERROR: Couldn't enable internal threads. Possible reasons:
         *  - error occured during signal masking (none in this case)
         *  - error occured during threading initialization
         */
        return 1;
    }

    CRYPTO_THREAD w1, w2;
    if ((w1 = CRYPTO_THREAD_provide(worker_cb)) == NULL) {
        /* ERROR: Couldn't provide a worker thread. This will happen if you're
         * on an unsupported architecture. */
        return 1;
    }
    if ((w2 = CRYPTO_THREAD_provide(worker_kill_after_single_job)) == NULL)
        return 1;

    int data1 = 1, data2 = 2, data3 = 3;
    CRYPTO_THREAD t1_1, t1_2, t1_3;
    if ((t1_1 = CRYPTO_THREAD_new(rt, &data1)) == NULL) {
        /* ERROR: Couldn't create a thread. This will happen if you're on
         * an unsupported architecture. */
        return 1;
    }
    if ((t1_2 = CRYPTO_THREAD_new(rt, &data2)) == NULL)
        return 1;
    if ((t1_3 = CRYPTO_THREAD_new(rt, &data3)) == NULL)
        return 1;

    unsigned long retval;

    /* we can join a task that we've spawned */
    CRYPTO_THREAD_join(t1_1, &retval);
    printf("Thread T1.1 exitted with return value: %ld.\n", retval);

    /* let's wait til all workers finish */
    CRYPTO_THREAD_join(w2, &retval);
    printf("Single-job worker finished\n");

    CRYPTO_THREAD_join(w1, &retval);
    printf("Work until there's jobs worker finished\n");

    /* necessary cleanup */
    CRYPTO_THREAD_clean(&t1_1);
    CRYPTO_THREAD_clean(&t1_2);
    CRYPTO_THREAD_clean(&t1_3);
    CRYPTO_THREAD_clean(&w1);
    CRYPTO_THREAD_clean(&w2);

    /* as you setup signal blocking, you're responsible for cleaning it up */
    CRYPTO_SIGNAL_unblock_all();

    /* The following should fail. */
    if (CRYPTO_THREAD_EXTERN_disable() == 0) {
        /* ERROR: Couldn't disable external threads. This would happen only
         * if signal unmasking couldn't be performed. */
        return 1;
    }

    /* The following should fail. */
    CRYPTO_THREAD t2;
    if ((t2 = CRYPTO_THREAD_provide(worker_cb)) != NULL) {
        /* Shouldn't happen. */
        return 1;
    }

    return 0;
}
