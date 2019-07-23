#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>

#ifdef _WIN32
# include <windows.h>
#else
# include <unistd.h>
#endif

#include <openssl/crypto.h>

int main(void)
{
    while(1)
        sleep(1);
    return 0;
}
