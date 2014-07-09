#ifndef SS_CRYPTO_H
#define SS_CRYPTO_H

#include <openssl/evp.h>

extern char password[MAX_PWD_LEN + 1];
extern char method[MAX_METHOD_NAME_LEN + 1];
extern int iv_len;

int crypto_init(char *key, char *method);
void crypto_exit(void);
int encrypt(int sockfd, struct link *ln);
int decrypt(int sockfd, struct link *ln);

#endif
