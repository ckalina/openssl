#include "blake2b.h"

int blake2b_nokey(void *out, size_t outlen, const void *in, size_t inlen) {
    EVP_MD_CTX *mdctx = NULL;

    if((mdctx = EVP_MD_CTX_create()) == NULL)
        goto fail;

    if(EVP_DigestInit_ex(mdctx, EVP_blake2b512(), NULL) != 1)
        goto fail;

    if(EVP_DigestUpdate(mdctx, in, inlen) != 1)
        goto fail;

    if(EVP_DigestFinal_ex(mdctx, out, (unsigned int *) &outlen) != 1)
        goto fail;

    if(NULL == out || outlen == 0 || outlen > BLAKE2B_OUTBYTES)
        goto fail;

    return 1;

fail:
    EVP_MD_CTX_destroy(mdctx);
    return 0;
}

int blake2b(void *out, size_t outlen, const void *in, size_t inlen,
                   const void *key, size_t keylen) {
    if (key == NULL || keylen == 0)
        return blake2b_nokey(out, outlen, in, inlen);

    const EVP_MAC *mac = EVP_get_macbynid(EVP_MAC_BLAKE2B);
    EVP_MAC_CTX *ctx = NULL;

    if((ctx = EVP_MAC_CTX_new(mac)) == NULL)
        goto fail;

    if(keylen > 0 && EVP_MAC_ctrl(ctx, EVP_MAC_CTRL_SET_KEY, key, keylen) <= 0)
            goto fail;

    if(!EVP_MAC_init(ctx))
        goto fail;

    if(!EVP_MAC_update(ctx, in, inlen))
        goto fail;

    if(!EVP_MAC_final(ctx, out, &outlen))
        goto fail;

    if(NULL == out || outlen == 0 || outlen > BLAKE2B_OUTBYTES)
        goto fail;

    if((NULL == key && keylen > 0) || keylen > BLAKE2B_KEYBYTES)
        goto fail;

    return 1;

fail:
    return 0;
}

int blake2b_long(void *pout, uint32_t outlen, const void *in, size_t inlen) {
    unsigned char *out = (unsigned char *)pout;
    uint8_t outlen_bytes[sizeof(uint32_t)] = {0};

    if(outlen > UINT32_MAX)
        goto fail;

    /* Ensure little-endian byte order! */
    store32(outlen_bytes, (uint32_t)outlen);

    EVP_MD_CTX *mdctx;

    if((mdctx = EVP_MD_CTX_create()) == NULL)
        goto fail;

    if(outlen <= BLAKE2B_OUTBYTES) {
        if (EVP_DigestInit_ex(mdctx, EVP_blake2b512(), NULL) != 1)
            goto fail;

        if(EVP_DigestUpdate(mdctx, outlen_bytes, sizeof(outlen_bytes)) != 1)
            goto fail;

        if(EVP_DigestUpdate(mdctx, in, inlen) != 1)
            goto fail;

        if(EVP_DigestFinal_ex(mdctx, out, &outlen) != 1)
            goto fail;
    } else {
        uint32_t toproduce;
        uint8_t out_buffer[BLAKE2B_OUTBYTES];
        uint8_t in_buffer[BLAKE2B_OUTBYTES];

        if(EVP_DigestInit_ex(mdctx, EVP_blake2b512(), NULL) != 1)
            goto fail;

        if(EVP_DigestUpdate(mdctx, outlen_bytes, sizeof(outlen_bytes)) != 1)
            goto fail;

        if(EVP_DigestUpdate(mdctx, in, inlen) != 1)
            goto fail;

        unsigned int outlen_tmp = BLAKE2B_OUTBYTES;
        if(EVP_DigestFinal_ex(mdctx, out_buffer, &outlen_tmp) != 1)
            goto fail;

        memcpy(out, out_buffer, BLAKE2B_OUTBYTES / 2);
        out += BLAKE2B_OUTBYTES / 2;
        toproduce = (uint32_t)outlen - BLAKE2B_OUTBYTES / 2;

        while(toproduce > BLAKE2B_OUTBYTES) {
            memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
            if (blake2b(out_buffer, BLAKE2B_OUTBYTES, in_buffer,
                              BLAKE2B_OUTBYTES, NULL, 0) != 1)
                goto fail;
            memcpy(out, out_buffer, BLAKE2B_OUTBYTES / 2);
            out += BLAKE2B_OUTBYTES / 2;
            toproduce -= BLAKE2B_OUTBYTES / 2;
        }

        memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
        if(blake2b(out_buffer, toproduce, in_buffer, BLAKE2B_OUTBYTES,
                   NULL, 0) != 1)
            goto fail;
        memcpy(out, out_buffer, toproduce);
    }

    return 1;
fail:
    EVP_MD_CTX_destroy(mdctx);
    return 0;
}
