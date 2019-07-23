#include <stdio.h>
#include <unistd.h>
#include <openssl/crypto.h>

unsigned long rt1(void *data) {
    printf("Thread created with data: %d.\n", *(int*)data);
    sleep(5);
    printf("Thread exitting.\n");
    return 1;
}

unsigned long rt2(void *data) {
    printf("Thread created with data: %d.\n", *(int*)data);
    printf("Thread exitting.\n");
    return 1;
}

int main(void)
{
    int data = 5;

    /* Attempting to create thread without explicit agreement. Should fail. */
    CRYPTO_THREAD t0;
    if ((t0 = CRYPTO_THREAD_new(rt1, &data)) != NULL) {
        /* ERROR: Created thread without explicit agreement. Cannot happen. */
        return 1;
    }

    /* Allow internal threads. */
    CRYPTO_SIGNAL* s[] = {NULL};
    if (CRYPTO_THREAD_INTERN_enable((CRYPTO_SIGNAL**)&s) == 0) {
        /* ERROR: Couldn't enable internal threads. Possible reasons:
         *  - error occured during signal masking (none in this case)
         *  - error occured during threading initialization
         */
        return 1;
    }

    CRYPTO_THREAD t1_1;
    if ((t1_1 = CRYPTO_THREAD_new(rt1, &data)) == NULL) {
        /* ERROR: Couldn't create a thread. This will happen if you're on
         * an unsupported architecture. */
        return 1;
    }

    CRYPTO_THREAD t1_2;
    if ((t1_2 = CRYPTO_THREAD_new(rt2, &data)) == NULL) {
        /* ERROR: Couldn't create a thread. This will happen if you're on
         * an unsupported architecture. */
        return 1;
    }

    unsigned long retval1;
    CRYPTO_THREAD_join(t1_1, &retval1);

    unsigned long retval2;
    CRYPTO_THREAD_join(t1_2, &retval2);

    printf("retval t1_1: %ld, retval t1_2: %ld\n", retval1, retval2);

    /* necessary cleanup */
    CRYPTO_THREAD_clean(&t1_1);
    CRYPTO_THREAD_clean(&t1_2);

    /* Disallow internal threads again. */
    if (CRYPTO_THREAD_INTERN_disable() == 0) {
        /* ERROR: Couldn't disable internal threads. This would happen only
         * if signal unmasking couldn't be performed. */
        return 1;
    }

    CRYPTO_SIGNAL_unblock_all();

    /* The following should fail. */
    CRYPTO_THREAD t2;
    if ((t2 = CRYPTO_THREAD_new(rt1, &data)) != NULL) {
        /* Shouldn't happen. */
        return 1;
    }

    return 0;
}
