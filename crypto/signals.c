/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"
#include <string.h>

#if defined(OPENSSL_SYS_WINDOWS) || defined(_WIN32) || defined(__CYGWIN__)

# include <windows.h>

volatile PHANDLER_ROUTINE callback_handler = NULL;

volatile CRYPTO_SIGNAL_CALLBACK cb_ctrl_c = NULL;
volatile CRYPTO_SIGNAL_CALLBACK cb_ctrl_break = NULL;
volatile CRYPTO_SIGNAL_CALLBACK cb_ctrl_close = NULL;

BOOL WINAPI CRYPTO_SIGNAL_handler(DWORD dwType)
{
    switch(dwType) {
    case CTRL_C_EVENT:
        if (cb_ctrl_c != NULL) {
            cb_ctrl_c((int)dwType);
            return TRUE;
        } else {
            return FALSE;
        }
    case CTRL_BREAK_EVENT:
        if (cb_ctrl_break != NULL) {
            cb_ctrl_break((int)dwType);
            return TRUE;
        } else {
            return FALSE;
        }
    case CTRL_CLOSE_EVENT:
        if (cb_ctrl_close != NULL) {
            cb_ctrl_close((int)dwType);
            return TRUE;
        } else {
            return FALSE;
        }
    default:
        return FALSE;
    }
}

int CRYPTO_SIGNAL_block(int signal, CRYPTO_SIGNAL_CALLBACK cb)
{
    PHANDLER_ROUTINE handler = (PHANDLER_ROUTINE) CRYPTO_SIGNAL_handler;

    switch(signal) {
    case CTRL_C_EVENT:
        cb_ctrl_c = cb;
        break;
    case CTRL_BREAK_EVENT:
        cb_ctrl_break = cb;
        break;
    case CTRL_CLOSE_EVENT:
        cb_ctrl_close = cb;
        break;
    }

    /* Associate handler if there are any signals and no handler has been
     * set. */
    if (cb_ctrl_c != NULL || cb_ctrl_break != NULL || cb_ctrl_close != NULL) {
        if (callback_handler == NULL) {
            callback_handler = (PHANDLER_ROUTINE) CRYPTO_SIGNAL_handler;
            if (SetConsoleCtrlHandler(callback_handler, TRUE) == 0)
                return 0;
        }
    } else {
        if (callback_handler != NULL) {
            if (SetConsoleCtrlHandler(callback_handler, FALSE) == 0)
                return 0;
            callback_handler = NULL;
        }
    }

    return 1;
}

#endif

#if defined(OPENSSL_SYS_UNIX) || defined (__unix__) || \
   (defined (__APPLE__) && defined (__MACH__))

# include <sys/types.h>
# include <unistd.h>
# include <signal.h>

/**
 * signal specifies which signal to (un)block/(un)mask
 * callback is one of:
 *     NULL, SIG_DFL   restores default signal handling
 *     SIG_IGN         blocks signal (if possible)
 *     void (*)(int)   masks signal and calls a callback upon receive
 */
int CRYPTO_SIGNAL_block(int signal, void (*callback)(int))
{
    int how;
    sigset_t sigs;
    struct sigaction sa;

    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = callback;

    if (sigemptyset (&sa.sa_mask) != 0 || sigaction(signal, &sa, NULL) != 0)
        goto fail;

    if (callback == NULL || callback == SIG_DFL)
        how = SIG_UNBLOCK;
    else if (callback == SIG_IGN)
        how = SIG_BLOCK;
    else
        how = SIG_SETMASK;

    if (callback == SIG_IGN) {
        if (sigemptyset(&sigs) != 0 || sigaddset(&sigs, signal) != 0)
            goto fail;
        if (sigprocmask(how, &sigs, NULL) != 0)
            goto fail;
    }

    return 1;

fail:
    /* An error happened during signal blocking. Disable resume */
    if (callback != NULL)
        CRYPTO_SIGNAL_block(signal, SIG_DFL);
    return 0;
}

int CRYPTO_SIGNAL_block_set(CRYPTO_SIGNAL_PROPS* props)
{
    CRYPTO_SIGNAL_PROPS* props_iter;
    for (props_iter = props; *props != NULL; ++props_iter)
        if (CRYPTO_SIGNAL_block(props_iter->signal, props_iter->callback) != 1)
            goto fail;

    return 1;

fail:
    for (; prop_iter != props; --prop_iter)
        if (CRYPTO_SIGNAL_block(props_iter->signal, NULL) != 1)
            goto fail;
    return 0;
}

#endif

