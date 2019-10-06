#include "openssl/crypto.h"
#include "internal/threads.h"

void * CRYPTO_THREAD_new(CRYPTO_THREAD_ROUTINE start, void* data,
                         unsigned long* ret)
{
	void* thread = NULL;
	if (CRYPTO_THREAD_EXTERN_enabled == 1) {
		thread = CRYPTO_THREAD_EXTERN_add_job(start, data);
		if (ret != NULL)
			*ret = (thread == NULL) ? 0 : 1;
	}
	else if (CRYPTO_THREAD_INTERN_enabled == 1) {
		thread = CRYPTO_THREAD_INTERN_new(start, data, ret);
	}
	return thread;
}

int CRYPTO_THREAD_join(void* thread, unsigned long* retval)
{
	if (CRYPTO_THREAD_EXTERN_enabled == 1)
		return CRYPTO_THREAD_EXTERN_join(thread, retval);
	if (CRYPTO_THREAD_INTERN_enabled == 1)
		return CRYPTO_THREAD_INTERN_join(thread, retval);
	return 0;
}

long int CRYPTO_THREAD_provide(CRYPTO_THREAD_CALLBACK cb)
{
	long ret;
	CRYPTO_THREAD_EXTERN_provide(&ret, cb);
	return ret;
}