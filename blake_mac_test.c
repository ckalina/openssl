#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/kdferr.h>
#include <openssl/objects.h>
#include <openssl/crypto.h>

# include <openssl/evp.h>
# include <openssl/objects.h>
# include <openssl/crypto.h>


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

	size_t outlen = atoi(argv[3]);

	uint8_t * out = malloc(outlen+1);

	uint8_t in22[] = "123123123";
	uint8_t *in2 = (uint8_t*) in22;

if (outlen == 64) {
	EVP_MD_CTX *mdctx;

	if ((mdctx = EVP_MD_CTX_create()) == NULL)
		goto fail;

	if (EVP_DigestInit_ex(mdctx, EVP_blake2b512(), NULL) != 1)
		goto fail;

	if (EVP_DigestUpdate(mdctx, in, inlen) != 1)
		goto fail;

	if (EVP_DigestFinal_ex(mdctx, out, (unsigned int *) &outlen) != 1)
		goto fail;

	print_hex(out, outlen);
	printf("\n");
}

	EVP_MAC_CTX *ctx = NULL;
	const EVP_MAC *mac = EVP_get_macbynid(EVP_MAC_BLAKE2B);

	if (mac == NULL)
	goto fail;

	if ((ctx = EVP_MAC_CTX_new(mac)) == NULL)
		goto fail;

	if (EVP_MAC_ctrl(ctx, EVP_MAC_CTRL_SET_SIZE, outlen, NULL) <= 0)
		goto fail;

	if (!EVP_MAC_init(ctx))
		return 11;

	if (!EVP_MAC_update(ctx, in2, inlen))
		return 12;

	if (!EVP_MAC_final(ctx, out, &outlen))
		goto fail;

	print_hex(out, outlen);
fail:
	return 1;

/*
	#ifdef ARGON2I
	const EVP_KDF *kdf = EVP_get_kdfbynid(EVP_KDF_ARGON2I);
	#endif
	#ifdef ARGON2D
	const EVP_KDF *kdf = EVP_get_kdfbynid(EVP_KDF_ARGON2D);
	#endif
	#ifdef ARGON2ID
	const EVP_KDF *kdf = EVP_get_kdfbynid(EVP_KDF_ARGON2ID);
	#endif

	if (kdf == NULL) {
		fprintf(stderr, "EVP_get_kdfbynid failed.\n");
		return 1;
	}

	EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);

	if (ctx == NULL) {
		fprintf(stderr, "EVP_KDF_CTX_new failed.\n");
		return 1;
	}

	if (EVP_KDF_ctrl(ctx, EVP_KDF_CTRL_SET_PASS, in, inlen) != 1) {
		fprintf(stderr, "Unable to set pass via ctrl.\n");
		return 1;
	}

	if (EVP_KDF_ctrl(ctx, EVP_KDF_CTRL_SET_SALT, salt, saltlen) != 1) {
		fprintf(stderr, "Unable to set salt via ctrl.\n");
		return 1;
	}

	if (EVP_KDF_derive(ctx, out, outlen) != 1) {
		fprintf(stderr, "Error occured during derive.");
		return 1;
	}

	print_hex(out, outlen);

	free(out);*/
	return 0;
}
