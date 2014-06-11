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
}

void crypto_exit(void)
{
	EVP_cleanup();
	ERR_free_strings();
}

void add_iv(struct link *ln)
{
	int i, iv_len, cipher_len;

	iv_len = EVP_CIPHER_iv_length(ln->evp_cipher);
	cipher_len = ln->cipher_len;

	for (i = cipher_len - 1; i >= 0; i--)
		ln->cipher[i + iv_len] = ln->cipher[i];

	for (i = 0; i < iv_len; i++)
		ln->cipher[i] = ln->iv[i];

	ln->cipher_len += iv_len;

	pr_link_info(ln);
	pr_info("added iv:\n");
	pr_iv(ln);
}

/* iv is in the first iv_len byptes of received buf */
void receive_iv(struct link *ln, int iv_len)
{
	int i;

	for (i = 0; i < iv_len; i++)
		ln->iv[i] = ln->cipher[i];

	ln->iv[iv_len] = '\0';

	/* exclude iv from buf */
	for (i = iv_len; i < CIPHER_BUF_SIZE; i++)
		ln->cipher[i - iv_len] = ln->cipher[i];

	ln->cipher_len -= iv_len;

	pr_link_info(ln);
	pr_info("received iv:\n");
	pr_iv(ln);
}

int create_cipher(struct link *ln, bool iv)
{
	const EVP_MD *md;
	int key_len, iv_len;

	md = EVP_get_digestbyname("MD5");
	if (md == NULL)
		goto err;

	ln->evp_cipher = EVP_get_cipherbyname(method);
	if (ln->evp_cipher == NULL)
		goto err;

	key_len = EVP_CIPHER_key_length(ln->evp_cipher);
	iv_len = EVP_CIPHER_iv_length(ln->evp_cipher);

	if (iv)
		receive_iv(ln, iv_len);
	else
		if (RAND_bytes(ln->iv, iv_len) == -1)
			goto err;

	ln->iv[iv_len] = '\0';

	if (EVP_BytesToKey(ln->evp_cipher, md, NULL, passwd, strlen(passwd), 1,
			   ln->key, ln->iv) == 0)
		goto err;

	ln->key[key_len] = '\0';

	ln->ctx = EVP_CIPHER_CTX_new();
	if (ln == NULL)
		goto err;

	pr_link_info(ln);
	pr_iv(ln);
	pr_key(ln);
	pr_debug("%s succeeded\n", __func__);
	return 0;

err:
	ERR_print_errors_fp(stderr);
	pr_warn("%s failed\n", __func__);
	return -1;
}

int encrypt(struct link *ln)
{
	int len, cipher_len;

	if (ln->evp_cipher == NULL)
		if (create_cipher(ln, false) == -1)
			goto err;

	if (EVP_EncryptInit_ex(ln->ctx, ln->evp_cipher, NULL,
			       ln->key, ln->iv) != 1)
		goto err;

	if (EVP_EncryptUpdate(ln->ctx, ln->cipher, &len,
			      ln->text, ln->text_len) != 1)
		goto err;

	cipher_len = len;

	if (EVP_EncryptFinal_ex(ln->ctx, ln->cipher + len, &len) != 1)
		goto err;

	cipher_len += len;
	ln->cipher_len = cipher_len;

	pr_link_debug(ln);
	pr_text(ln);
	pr_cipher(ln);
	pr_debug("%s succeeded\n", __func__);
	return cipher_len;

err:
	ERR_print_errors_fp(stderr);
	pr_link_info(ln);
	pr_warn("%s failed\n", __func__);
	return -1;
}

int decrypt(struct link *ln)
{
	int len, text_len;
	/* cipher_len is the buf length excluding iv(if exist) */
	int cipher_len;

	if (!(ln->state & LINK_IV_EXCHANGED)) {
		if (create_cipher(ln, true) == -1)
			goto err;

		ln->state |= LINK_IV_EXCHANGED;
	}

	if (EVP_DecryptInit_ex(ln->ctx, ln->evp_cipher, NULL,
			       ln->key, ln->iv) != 1) {
		pr_link_debug(ln);
		pr_debug("EVP_DecryptInit_ex failed\n");
		goto err;
	}

	if (EVP_DecryptUpdate(ln->ctx, ln->text, &len,
			      ln->cipher, ln->cipher_len) != 1) {
		pr_link_debug(ln);
		pr_debug("EVP_DecryptUpdate failed\n");
		goto err;
	}


	text_len = len;

	if (EVP_DecryptFinal_ex(ln->ctx, ln->cipher + len, &len) != 1) {
		pr_link_debug(ln);
		pr_debug("EVP_DecryptUpdate failed\n");
		goto err;
	}

	text_len += len;
	ln->text_len = text_len;

	pr_link_info(ln);
	pr_cipher(ln);
	pr_text(ln);
	pr_info("%s succeeded\n", __func__);
	return text_len;

err:
	ERR_print_errors_fp(stderr);
	pr_link_warn(ln);
	pr_warn("%s failed\n", __func__);
	return -1;
}
