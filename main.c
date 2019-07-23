#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/kdferr.h>
#include <openssl/objects.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/obj_mac.h>

# define ARGON2_MIN_LANES UINT32_C(1)
# define ARGON2_MIN_THREADS UINT32_C(1)
# define ARGON2_MIN_OUTLEN UINT32_C(4)
# define ARGON2_MIN_MEMORY (2 * ARGON2_SYNC_POINTS) /* 2 blocks per slice */
# define ARGON2_MIN(a, b) ((a) < (b) ? (a) : (b))
# define ARGON2_MIN_TIME UINT32_C(1)
# define ARGON2_MIN_PWD_LENGTH UINT32_C(0)
# define ARGON2_MIN_AD_LENGTH UINT32_C(0)
# define ARGON2_MIN_SALT_LENGTH UINT32_C(8)
# define ARGON2_MIN_SECRET UINT32_C(0)

static EVP_KDF_CTX *get_kdfbyname(const char *name)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, name, NULL);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);

    EVP_KDF_free(kdf);
    return kctx;
}

static void print_hex(uint8_t *bytes, size_t bytes_len) {
	size_t i;
	for (i = 0; i < bytes_len; ++i)
		printf("%02x", bytes[i]);
	printf("\n");
}

int main(int argc, const char * argv[]) {
	if (argc < 3) return 1;

	uint8_t * in = (uint8_t*) argv[1];
	uint32_t inlen = strlen(argv[1]);

	uint8_t * salt = (uint8_t*) argv[2];
	uint32_t saltlen = strlen(argv[2]);

	size_t outlen = atoi(argv[3]);

	if (saltlen < ARGON2_MIN_SALT_LENGTH) return 2;
	if (outlen  < ARGON2_MIN_OUTLEN)      return 3;

	uint8_t * out = malloc(outlen+1);

	#ifdef ARGON2I
	EVP_KDF_CTX *ctx = get_kdfbyname(SN_argon2i);
	#endif
	#ifdef ARGON2D
	EVP_KDF_CTX *ctx = get_kdfbyname(SN_argon2d);
	#endif
	#ifdef ARGON2ID
	EVP_KDF_CTX *ctx = get_kdfbyname(SN_argon2id);
	#endif

	if (ctx == NULL) {
		fprintf(stderr, "EVP_KDF_CTX_new failed.\n");
		return 1;
	}

	OSSL_PARAM params[3], *p = params;
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, in, inlen);
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, saltlen);
	*p = OSSL_PARAM_construct_end();

        if (EVP_KDF_CTX_set_params(ctx, params) != 1) {
		fprintf(stderr, "Unable to set param via ctrl.\n");
		return 1;
	}

	if (EVP_KDF_derive(ctx, out, outlen) != 1) {
		fprintf(stderr, "Error occured during derive.");
		return 1;
	}

	print_hex(out, outlen);

	EVP_KDF_CTX_free(ctx);
	free(out);

	return 0;
}
