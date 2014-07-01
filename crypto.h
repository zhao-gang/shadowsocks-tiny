#ifndef SS_CRYPTO_H
#define SS_CRYPTO_H

#include <openssl/evp.h>

#define MAX_METHOD_NAME_LEN 17
#define MAX_KEY_LEN EVP_MAX_KEY_LENGTH + 1
#define MAX_IV_LEN EVP_MAX_IV_LENGTH + 1

extern char passwd[MAX_KEY_LEN];
extern char method[MAX_METHOD_NAME_LEN];
extern int iv_len;

int crypto_init(char *key, char *method);
void crypto_exit(void);
int encrypt(int sockfd, struct link *ln);
int decrypt(int sockfd, struct link *ln);

#endif
