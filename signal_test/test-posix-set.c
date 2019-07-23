    #include <stdio.h>

    #ifdef _WIN32
    # include <windows.h>
    long s = CTRL_C_EVENT;
    #else
    # include <unistd.h>
    # include <signal.h>
    long s = SIGINT;
    #endif

    #include <openssl/crypto.h>

    void cb(int sig) {
        static int count = 0;
        printf("Caught signal: %d\n", sig);
        printf("Total number of signals caught: %d\n", count++);
    }

    int main(void)
    {
        int counter = 0;

	CRYPTO_SIGNAL sig2 = { .signal = SIGINT, .callback = cb, };
	CRYPTO_SIGNAL sig1 = { .signal = SIGTERM, .callback = cb, };
	CRYPTO_SIGNAL sig3 = { .signal = SIGUSR1, .callback = cb, };

	CRYPTO_SIGNAL *sig[] = { &sig1, &sig2, &sig3, NULL };

        CRYPTO_SIGNAL_block_set((CRYPTO_SIGNAL**)&sig);

        while(counter++ < 10) {
            sleep(1);
        }
        return 0;
    }
