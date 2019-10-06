
/* @TODO #if defined(OPENSSL_SYS_UNIX)*/

#include <sys/types.h>
#include <unistd.h>

typedef struct {
    CRYPTO_THREAD_ROUTINE routine;
    CRYPTO_THREAD_DATA    data;
    CRYPTO_THREAD_RETVAL  retval;
    pthread_t*            handle;
} CRYPTO_THREAD_POSIX;

typedef pthread_mutex_t CRYPTO_MUTEX_POSIX;
typedef pthread_cond_t CRYPTO_CONDVAR_POSIX;

/* @TODO #endif */