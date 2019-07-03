#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/crypto.h>
#include <openssl/argon2.h>

static void print_hex(uint8_t *bytes, size_t bytes_len) {
	size_t i;
	for (i = 0; i < bytes_len; ++i)
		printf("%02x", bytes[i]);
	printf("\n");
}

int main(int argc, const char * argv[]) {

	uint8_t * in = (uint8_t*) argv[1];
	uint32_t inlen = strlen(argv[1]);

	/*char key_str[] = "this is a test";
	uint8_t * key = (uint8_t*) &key_str;
	uint32_t keylen = strlen(key_str);*/

	char salt_str[] = "salty much;padding:w";
	uint8_t * salt = (uint8_t*) &salt_str;
	uint32_t saltlen = strlen(salt_str);

	char out_str[65];
	uint8_t * out = (uint8_t*) &out_str;
	size_t outlen = 64;

#ifdef ARGON2D
	const EVP_MAC *mac = EVP_get_macbynid(EVP_MAC_ARGON2D);
#endif

#ifdef ARGON2I
	const EVP_MAC *mac = EVP_get_macbynid(EVP_MAC_ARGON2I);
#endif

#ifdef ARGON2ID
	const EVP_MAC *mac = EVP_get_macbynid(EVP_MAC_ARGON2ID);
#endif

	EVP_MAC_CTX *ctx = NULL;

	if((ctx = EVP_MAC_CTX_new(mac)) == NULL) {
		fprintf(stderr, "EVP_MAC_CTX_new failed\n");
		goto fail;
	}

	/*if (keylen > 0) {
		if (EVP_MAC_ctrl(ctx, EVP_MAC_CTRL_SET_KEY, key, keylen) <= 0) {
			fprintf(stderr, "EVP_MAC_ctrl failed\n");
			goto fail;
		}
	}*/
		if (EVP_MAC_ctrl(ctx, EVP_MAC_CTRL_SET_SALT, salt, saltlen)<=0){
			fprintf(stderr, "EVP_MAC_ctrl failed\n");
			goto fail;
		}
		if (EVP_MAC_ctrl(ctx, EVP_MAC_CTRL_SET_SIZE, outlen) <= 0) {
			fprintf(stderr, "EVP_MAC_ctrl failed\n");
			goto fail;
		}

	if (!EVP_MAC_init(ctx)) {
		fprintf(stderr, "init failed\n");
		goto fail;
	}

	if (EVP_MAC_update(ctx, in, inlen) != ARGON2_OK) {
		fprintf(stderr, "update failed\n");
		goto fail;
	}

	if (!EVP_MAC_final(ctx, out, &outlen)) {
		fprintf(stderr, "final failed\n");
		goto fail;
	}

	printf("Outlen: %ld\n", outlen);
	print_hex(out, outlen);

	return 0;

fail:
	return 1;
}
