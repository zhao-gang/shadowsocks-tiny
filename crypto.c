#include <string.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "common.h"
#include "crypto.h"

char password[MAX_KEY_LEN];
char method[MAX_METHOD_NAME_LEN];
int iv_len;
static const EVP_CIPHER *evp_cipher;
static const EVP_MD *md;
static char key[EVP_MAX_KEY_LENGTH];
static int key_len;

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

int get_method(char *password, char *method)
{
	int ret;

	md = EVP_get_digestbyname("MD5");
	if (md == NULL)
		goto err;

	evp_cipher = EVP_get_cipherbyname(method);
	if (evp_cipher == NULL)
		goto err;

	key_len = EVP_CIPHER_key_length(evp_cipher);
	iv_len = EVP_CIPHER_iv_length(evp_cipher);

	ret = EVP_BytesToKey(evp_cipher, md, NULL,
			     (void *)password, strlen(password), 1,
			     (void *)key, NULL);
	if (ret == 0)
		goto err;

	key[key_len] = '\0';
	pr_data(stdout, "password", password, strlen(password));
	pr_data(stdout, "key", key, key_len);
	return 0;
err:
	pr_warn("%s: method %s is not supported\n", __func__, method);
	return -1;
}

int crypto_init(char *password, char *method)
{
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	if (get_method(password, method) == -1)
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
	pr_data(stdout, "iv", iv_p, iv_len);

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
	pr_data(stdout, "iv", iv_p, iv_len);

	return 0;
err:
	sock_warn(sockfd, "%s failed", __func__);
	return -1;
}

static int check_cipher(int sockfd, struct link *ln, const char *type)
{
	int ret;
	char *iv_p;
	EVP_CIPHER_CTX *ctx_p;

	if (sockfd == ln->local_sockfd) {
		iv_p = ln->local_iv;
		ctx_p = ln->local_ctx;
	} else if (sockfd == ln->server_sockfd) {
		iv_p = ln->server_iv;
		ctx_p = ln->server_ctx;
	} else {
		goto err;
	}

	if (strcmp(type, "encrypt") == 0 &&
	    !(ln->state & SS_IV_SENT)) {
		if (RAND_bytes((void *)iv_p, iv_len) == -1)
			goto err;

		iv_p[iv_len] = '\0';

		ret = EVP_EncryptInit_ex(ctx_p, evp_cipher,
					 NULL, (void *)key,
					 (void *)iv_p);

		if (ret != 1)
			goto err;
	} else if (strcmp(type, "decrypt") == 0 &&
		   !(ln->state & SS_IV_RECEIVED)) {
		if (receive_iv(sockfd, ln) == -1)
			goto err;

		ret = EVP_DecryptInit_ex(ctx_p, evp_cipher,
					 NULL, (void *)key,
					 (void *)iv_p);

		if (ret != 1)
			goto err;
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

	if (check_cipher(sockfd, ln, "encrypt") == -1)
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
	pr_data(stdout, "text", ln->text, ln->text_len);

	if (EVP_EncryptUpdate(ctx_p, ln->cipher, &len,
			      ln->text, ln->text_len) != 1)
		goto err;

	cipher_len = len;
	ln->cipher_len = cipher_len;

	if (!(ln->state & SS_IV_SENT))
		if (add_iv(sockfd, ln) == -1)
			goto err;

	/* encryption succeeded, so text buffer is not needed */
	ln->text_len = 0;
	sock_debug(sockfd, "%s: after encrypt", __func__);
	pr_link_debug(ln);
	pr_data(stdout, "cipher", ln->cipher, ln->cipher_len);

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

	if (check_cipher(sockfd, ln, "decrypt") == -1)
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
	pr_data(stdout, "cipher", ln->cipher, ln->cipher_len);

	if (EVP_DecryptUpdate(ctx_p, ln->text, &len,
			      ln->cipher, ln->cipher_len) != 1) {
		goto err;
	}

	text_len = len;
	ln->text_len = text_len;
	/* decryption succeeded, so cipher buffer is not needed */
	ln->cipher_len = 0;

	sock_debug(sockfd, "%s: after decrypt", __func__);
	pr_link_debug(ln);
	pr_data(stdout, "text", ln->text, ln->text_len);

	return text_len;
err:
	ERR_print_errors_fp(stderr);
	pr_link_warn(ln);
	sock_warn(sockfd, "%s failed\n", __func__);
	return -1;
}
