
/* @TODO #if defined(OPENSSL_SYS_UNIX)*/

#include <windows.h>

typedef struct {
    CRYPTO_THREAD_ROUTINE routine;
    CRYPTO_THREAD_DATA    data;
    CRYPTO_THREAD_RETVAL  retval;
    HANDLE*               handle;
} CRYPTO_THREAD_WIN;

typedef CRITICAL_SECTION CRYPTO_MUTEX_WIN;
typedef CONDITION_VARIABLE CRYPTO_CONDVAR_WIN;