#include <string.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "common.h"
#include "crypto.h"

char passwd[MAX_KEY_LEN];
char method[MAX_METHOD_NAME_LEN];
static const EVP_CIPHER *evp_cipher;
static const EVP_MD *md;
static int iv_len, key_len;

static const char supported_method[][MAX_METHOD_NAME_LEN] = {
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
	md = EVP_get_digestbyname("MD5");
	if (md == NULL)
		goto err;

	evp_cipher = EVP_get_cipherbyname(method);
	if (evp_cipher == NULL)
		goto err;

	key_len = EVP_CIPHER_key_length(evp_cipher);
	iv_len = EVP_CIPHER_iv_length(evp_cipher);

	return 0;
err:
	pr_warn("%s: method %s is not supported\n", __func__, method);
	return -1;
}

int crypto_init(char *passwd, char *method)
{
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	if (get_method(passwd, method) == -1)
		return -1;

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
	char *iv_p;

	if (sockfd == ln->local_sockfd)
		iv_p = ln->local_iv;
	else if (sockfd == ln->server_sockfd)
		iv_p = ln->server_iv;
	else
		goto err;

	ret = add_data(sockfd, ln, "cipher", iv_p, iv_len);
	if (ret != 0)
		goto err;

	ln->state |= SS_IV_SENT;
	sock_debug(sockfd, "%s:", __func__);
	pr_link_debug(ln);

	return 0;
err:
	sock_warn(sockfd, "%s failed", __func__);
	return -1;
}

/* iv is in the first iv_len byptes of ss tcp/udp header */
int receive_iv(int sockfd, struct link *ln)
{
	int ret;
	char *iv_p;

	if (sockfd == ln->local_sockfd)
		iv_p = ln->local_iv;
	else if (sockfd == ln->server_sockfd)
		iv_p = ln->server_iv;
	else
		goto err;

	memcpy(iv_p, ln->cipher, iv_len);
	iv_p[iv_len] = '\0';

	ret = rm_data(sockfd, ln, "cipher", iv_len);
	if (ret != 0)
		goto err;

	ln->state |= SS_IV_RECEIVED;
	sock_debug(sockfd, "%s:", __func__);
	pr_link_debug(ln);

	return 0;
err:
	sock_warn(sockfd, "%s failed", __func__);
	return -1;
}

int check_cipher(int sockfd, struct link *ln)
{
	int ret;
	char *iv_p;
	char *key_p;
	EVP_CIPHER_CTX *ctx_p;

	if (sockfd == ln->local_sockfd) {
		iv_p = ln->local_iv;
		key_p = ln->local_key;
		ctx_p = ln->local_ctx;
	} else if (sockfd == ln->server_sockfd) {
		iv_p = ln->server_iv;
		key_p = ln->server_key;
		ctx_p = ln->server_ctx;
	} else {
		goto err;
	}

	if (strlen(iv_p) == 0) {
		if (RAND_bytes((void *)iv_p, iv_len) == -1)
			goto err;

		iv_p[iv_len] = '\0';
	}

	if (strlen(key_p) == 0) {
		ret = EVP_BytesToKey(evp_cipher, md, NULL,
				     (void *)passwd, strlen(passwd), 1,
				     (void *)key_p, (void *)iv_p);
		if (ret == 0)
			goto err;

		key_p[key_len] = '\0';

		/* key length is zero also means the cipher isn't
		 * initialized, we now have all the info to initialize
		 * the cipher */
		if (ln->state & SS_CLIENT) {
			if (sockfd == ln->local_sockfd)
				ret = EVP_EncryptInit_ex(ctx_p, evp_cipher,
							 NULL, (void *)key_p,
							 (void *)iv_p);
			else if (sockfd == ln->server_sockfd)
				ret = EVP_DecryptInit_ex(ctx_p, evp_cipher,
							 NULL, (void *)key_p,
							 (void *)iv_p);

			if (ret != 1)
				goto err;
		} else if (ln->state & SS_SERVER) {
			if (sockfd == ln->local_sockfd)
				ret = EVP_DecryptInit_ex(ctx_p, evp_cipher,
							 NULL, (void *)key_p,
							 (void *)iv_p);
			else if (sockfd == ln->server_sockfd)
				ret = EVP_EncryptInit_ex(ctx_p, evp_cipher,
							 NULL, (void *)key_p,
							 (void *)iv_p);

			if (ret != 1)
				goto err;
		}
	}

	return 0;
err:
	sock_warn(sockfd, "%s failed", __func__);
	return -1;
}

int encrypt(int sockfd, struct link *ln)
{
	int len, cipher_len;
	EVP_CIPHER_CTX *ctx_p;

	if (check_cipher(sockfd, ln) == -1)
		goto err;

	if (sockfd == ln->local_sockfd) {
		ctx_p = ln->local_ctx;
	} else if (sockfd == ln->server_sockfd) {
		ctx_p = ln->server_ctx;
	} else {
		goto err;
	}

	sock_debug(sockfd, "%s: before encrypt", __func__);
	pr_link_debug(ln);

	if (EVP_EncryptUpdate(ctx_p, ln->cipher, &len,
			      ln->text, ln->text_len) != 1)
		goto err;

	cipher_len = len;

	if (EVP_EncryptFinal_ex(ctx_p, ln->cipher + len, &len) != 1)
		goto err;

	cipher_len += len;
	ln->cipher_len = cipher_len;

	if (!(ln->state & SS_IV_SENT))
		if (add_iv(sockfd, ln) == -1)
			goto err;

	/* encryption succeeded, so text buffer is not needed */
	ln->text_len = 0;
	sock_debug(sockfd, "%s: after encrypt", __func__);
	pr_link_debug(ln);

	return ln->cipher_len;
err:
	ERR_print_errors_fp(stderr);
	pr_link_warn(ln);
	sock_warn(sockfd, "%s failed", __func__);
	return -1;
}

int decrypt(int sockfd, struct link *ln)
{
	int len, text_len;
	EVP_CIPHER_CTX *ctx_p;

	if (!(ln->state & SS_IV_RECEIVED))
		if (receive_iv(sockfd, ln) == -1)
			goto err;

	if (check_cipher(sockfd, ln) == -1)
		goto err;

	if (sockfd == ln->local_sockfd) {
		ctx_p = ln->local_ctx;
	} else if (sockfd == ln->server_sockfd) {
		ctx_p = ln->server_ctx;
	} else {
		goto err;
	}

	sock_debug(sockfd, "%s: before decrypt", __func__);
	pr_link_debug(ln);

	if (EVP_DecryptUpdate(ctx_p, ln->text, &len,
			      ln->cipher, ln->cipher_len) != 1) {
		goto err;
	}

	text_len = len;

	if (EVP_DecryptFinal_ex(ctx_p, ln->cipher + len, &len) != 1) {
		goto err;
	}

	text_len += len;
	ln->text_len = text_len;
	/* decryption succeeded, so cipher buffer is not needed */
	ln->cipher_len = 0;

	sock_debug(sockfd, "%s: after decrypt", __func__);
	pr_link_debug(ln);

	return text_len;
err:
	ERR_print_errors_fp(stderr);
	pr_link_warn(ln);
	sock_warn(sockfd, "%s failed\n", __func__);
	return -1;
}
