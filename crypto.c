#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <netdb.h>

#include "common.h"
#include "crypto.h"

char passwd[MAX_KEY_LEN];
char method[MAX_METHOD_NAME_LEN];

const char supported_method[][MAX_METHOD_NAME_LEN] = {
	"aes-128-cfb",
	"aes-192-cfb",
	"aes-256-cfb",
	"bf-cfb",
	"camellia-128-cfb",
	"camellia-192-cfb",
	"camellia-256-cfb",
	"cast5-cfb",
	"des-cfb",
	"idea-cfb",
	"rc2-cfb",
	"rc4",
	"seed-cfb",
	"salsa20-ctr",
};

int get_method(char *passwd, char *method)
{
	int i = 0;
	int len = sizeof(supported_method) / MAX_METHOD_NAME_LEN;

	while (i < len)
		if (strcmp(method, supported_method[i++]) == 0)
			return 0;

	pr_warn("method %s is not supported\n", method);
	return -1;
}

int crypto_init(char *passwd, char *method)
{
	if (get_method(passwd, method) == -1)
		return -1;

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	return 0;
}

void crypto_exit(void)
{
	EVP_cleanup();
	ERR_free_strings();
}

int add_iv(int sockfd, struct link *ln)
{
	int ret;
	int iv_len = EVP_CIPHER_iv_length(ln->evp_cipher);

	ret = add_data(sockfd, ln, "cipher", ln->iv, iv_len);
	if (ret != 0) {
		sock_warn(sockfd, "%s failed", __func__);
	}

	return ret;
}

/* iv is in the first iv_len byptes of received buf */
int receive_iv(int sockfd, struct link *ln)
{
	int ret;
	int iv_len;

	if (!ln->evp_cipher) {
		ln->evp_cipher = EVP_get_cipherbyname(method);
		if (!ln->evp_cipher)
			return -1;
	}

	iv_len = EVP_CIPHER_iv_length(ln->evp_cipher);
	memcpy(ln->iv, ln->cipher, iv_len);
	ln->iv[iv_len] = '\0';
	ret = rm_data(sockfd, ln, "cipher", iv_len);
	if (ret != 0) {
		sock_warn(sockfd, "%s failed", __func__);
	}

	return ret;
}

int create_cipher(struct link *ln, bool iv)
{
	const EVP_MD *md;
	int key_len, iv_len;

	md = EVP_get_digestbyname("MD5");
	if (md == NULL)
		goto err;

	if (!ln->evp_cipher) {
		ln->evp_cipher = EVP_get_cipherbyname(method);
		if (ln->evp_cipher == NULL)
			goto err;
	}

	key_len = EVP_CIPHER_key_length(ln->evp_cipher);
	iv_len = EVP_CIPHER_iv_length(ln->evp_cipher);

	if (!iv) {
		if (RAND_bytes((void *)ln->iv, iv_len) == -1)
			goto err;

		ln->iv[iv_len] = '\0';
	}

	if (EVP_BytesToKey(ln->evp_cipher, md, NULL,
			   (void *)passwd, strlen(passwd), 1,
			   (void *)ln->key, (void *)ln->iv) == 0)
		goto err;

	ln->key[key_len] = '\0';

	ln->ctx = EVP_CIPHER_CTX_new();
	if (ln == NULL)
		goto err;

	return 0;

err:
	ERR_print_errors_fp(stderr);
	pr_warn("%s failed\n", __func__);
	return -1;
}

int encrypt(int sockfd, struct link *ln)
{
	int len, cipher_len;

	if (ln->evp_cipher == NULL)
		if (create_cipher(ln, false) == -1)
			goto err;

	if (EVP_EncryptInit_ex(ln->ctx, ln->evp_cipher, NULL,
			       (void *)ln->key, (void *)ln->iv) != 1)
		goto err;

	if (EVP_EncryptUpdate(ln->ctx, (void *)ln->cipher, &len,
			      (void *)ln->text, ln->text_len) != 1)
		goto err;

	cipher_len = len;

	if (EVP_EncryptFinal_ex(ln->ctx, (void *)(ln->cipher + len), &len) != 1)
		goto err;

	cipher_len += len;
	ln->cipher_len = cipher_len;

	return cipher_len;

err:
	ERR_print_errors_fp(stderr);
	pr_link_warn(ln);
	sock_warn(sockfd, "%s failed", __func__);
	return -1;
}

int decrypt(int sockfd, struct link *ln)
{
	int len, text_len;

	if (ln->ctx == NULL)
		if (create_cipher(ln, true) == -1)
			goto err;

	if (EVP_DecryptInit_ex(ln->ctx, ln->evp_cipher, NULL,
			       (void *)ln->key, (void *)ln->iv) != 1) {
		goto err;
	}

	if (EVP_DecryptUpdate(ln->ctx, (void *)ln->text, &len,
			      (void *)ln->cipher, ln->cipher_len) != 1) {
		goto err;
	}

	text_len = len;

	if (EVP_DecryptFinal_ex(ln->ctx, (void *)(ln->cipher + len), &len) != 1) {
		goto err;
	}

	text_len += len;
	ln->text_len = text_len;

	return text_len;

err:
	ERR_print_errors_fp(stderr);
	pr_link_warn(ln);
	sock_warn(sockfd, "%s failed\n", __func__);
	return -1;
}
